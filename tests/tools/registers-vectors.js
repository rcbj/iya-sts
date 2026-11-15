// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: registers-vectors.js
//
// ---------------------------------------------------------------------------
// THE REGISTERS OVER THE DIRECTORY (#444, phase 4): what the Node service's
// registers answer, refusal by refusal and code by code, for the Rust crate
// `sts-registers` to reproduce. Called by `tests/tools/crypto-vectors.js`'s
// `registers-node.json` row, in a process of its own.
//
// THE METHOD IS A RECORDING OF EVERY PORT. The registers sit over the
// directory, the settings, the audit log and one another, and the Rust crate
// reaches each of those through a small trait of its own (the directory is
// another slice's crate, written at the same time). So each step drives the
// REAL Node module, over the real in-memory directory `ldap/ldap_server.js`
// builds, with every dependency the Rust crate takes as a port wrapped in a
// recorder: each call is written down with its arguments and its answer.
// The Rust test replays those answers to its own register and checks two
// things — that it made the same calls with the same arguments (the
// directory writes above all: an entry Rust writes is the entry Node
// writes), and that it gave the same answer, sentence and code.
//
// A call made from inside another recorded call is not recorded: it is the
// port's own business. Settings are recorded as `settings.value` calls and
// replayed by key.
// ---------------------------------------------------------------------------

const path = require('path');

/**
 * A JSON copy of what crossed a port: functions dropped, `undefined` dropped
 * from objects and `null` in arrays, as JSON.stringify does.
 *
 * @param {any} value - anything
 * @returns {any} its JSON image
 */
function clone(value) {
  // Only a TRUE cycle (an object inside itself) is cut: an object shared
  // by two members, as a register's answer often is, is written twice.
  const ancestors = [];
  const copy = function (v) {
    if (v === undefined || typeof v === 'function' || typeof v === 'symbol') {
      return undefined;
    }
    if (typeof v === 'bigint') {
      return String(v);
    }
    if (v === null || typeof v !== 'object') {
      return typeof v === 'number' && !isFinite(v) ? null : v;
    }
    if (typeof v.toJSON === 'function') {
      return copy(v.toJSON());
    }
    if (ancestors.indexOf(v) >= 0) {
      return '[cycle]';
    }
    ancestors.push(v);
    let out;
    if (Array.isArray(v)) {
      out = v.map(function (one) {
        const c = copy(one);
        return c === undefined ? null : c;
      });
    } else {
      out = {};
      Object.keys(v).forEach(function (k) {
        const c = copy(v[k]);
        if (c !== undefined) {
          out[k] = c;
        }
      });
    }
    ancestors.pop();
    return out;
  };
  const out = copy(value);
  return out === undefined ? null : out;
}

/**
 * The recorder every wrapped port writes to.
 *
 * @param {any} errorCodes - common/error_codes.js
 * @returns {any} the recorder
 */
function recorder(errorCodes) {
  const rec = { calls: null, depth: 0, opaque: [] };
  rec.codeOf = function (value) {
    if (!value || typeof value !== 'object') {
      return null;
    }
    return errorCodes.codeOf(value) || null;
  };
  rec.fn = function (port, method, f) {
    return function () {
      const args = Array.prototype.slice.call(arguments);
      if (!rec.calls || rec.depth > 0) {
        return f.apply(this, args);
      }
      rec.depth += 1;
      let answer;
      let threw = null;
      try {
        answer = f.apply(this, args);
      } catch (e) {
        threw = e;
      } finally {
        rec.depth -= 1;
      }
      // A module handed as an argument (`settingFor(app, key, config)`)
      // is recorded by name, not by its whole table.
      const row = { port: port, method: method,
                    args: clone(args.map(function (one) {
                      return rec.opaque.indexOf(one) >= 0 ? '[module]' : one;
                    })) };
      if (threw) {
        row.threw = String((threw && threw.message) || threw);
        rec.calls.push(row);
        throw threw;
      }
      row.answer = clone(answer);
      const code = rec.codeOf(answer);
      if (code) {
        row.code = code;
      }
      rec.calls.push(row);
      return answer;
    };
  };
  rec.object = function (port, target, only) {
    return new Proxy(target, {
      get: function (t, key) {
        const v = t[key];
        if (typeof key !== 'string' || (only && only.indexOf(key) < 0)) {
          return v;
        }
        if (typeof v === 'function') {
          return rec.fn(port, key, v.bind(t));
        }
        if (rec.calls && rec.depth === 0 && v !== undefined &&
            Object.prototype.hasOwnProperty.call(t, key)) {
          rec.calls.push({ port: port, method: key, args: [],
                           answer: clone(v) });
        }
        return v;
      }
    });
  };
  rec.step = function (steps, register, op, input, run) {
    rec.calls = [];
    let answer;
    let threw = null;
    try {
      answer = run();
    } catch (e) {
      threw = String((e && e.message) || e);
    }
    const calls = rec.calls;
    rec.calls = null;
    const row = { register: register, op: op, input: clone(input),
                  answer: clone(answer), code: rec.codeOf(answer),
                  calls: calls };
    if (threw) {
      row.threw = threw;
    }
    steps.push(row);
    return answer;
  };
  return rec;
}

/**
 * Builds the vectors.
 *
 * @param {string} ROOT - the repository root
 * @returns {Promise<any>} the vector document
 */
async function build(ROOT) {
  const req = function (rel) {
    return require(path.join(ROOT, rel));
  };
  const errorCodes = req('common/error_codes');
  const rec = recorder(errorCodes);
  const config = req('common/config');
  const realValue = config.value;
  config.value = rec.fn('settings', 'value', realValue);
  rec.opaque.push(config);

  // The slots the directory fills at its require, wrapped before it is
  // required so that what it installs is recorded.
  const roles = req('common/roles');
  const adminRbacModule = req('admin-ui/admin_rbac');
  const realRolesSet = roles.setDirectory;
  roles.setDirectory = function (hooks) {
    return realRolesSet(hooks ? rec.object('roles.directory', hooks) : hooks);
  };
  const realRbacSet = adminRbacModule.setDirectory;
  adminRbacModule.setDirectory = function (view) {
    const wrapped = Object.assign({}, view);
    if (typeof view.forRealm === 'function') {
      wrapped.forRealm = function (id) {
        const inner = view.forRealm(id);
        return inner ? rec.object('rbac.directory', inner) : inner;
      };
    }
    return realRbacSet(rec.object('rbac.directory', wrapped));
  };
  const ldap = req('ldap/ldap_server');
  const applications = req('common/applications');
  const audit = req('common/audit');
  const helpers = req('common/helpers');

  // A fixed population, made before anything is recorded.
  ['dora', 'emil'].forEach(function (name) {
    ldap.createUser(name, { origin: 'seed', note: 'vectors', invent: false,
                            attributes: {} });
  });
  ldap.createGroup('g-staff', { origin: 'seed', members: ['dora'] });
  applications.createApplication({
    identifier: 'app-res', protocols: ['oauth2'],
    fields: { oauthPermissionBaseUri: 'https://api.example',
              oauthPermission: ['write|Write things', 'read'],
              oauthRoleGatedPermission: ['write'] } });
  applications.createApplication({
    identifier: 'app-cli', protocols: ['oauth2'],
    fields: { oauthScope: ['openid'] } });

  const steps = [];
  const auditPort = rec.object('audit', audit,
                               ['audit', 'record', 'failure']);
  const appsPort = rec.object('applications', applications);
  const AdminActions = req('admin-core/admin_actions').AdminActions;
  const AdminRbac = adminRbacModule.AdminRbac;
  const bootstrapName = req('common/bootstrap_name');
  bootstrapName.current = rec.fn('bootstrap', 'current',
                                 bootstrapName.current.bind(bootstrapName));
  const rbac = new AdminRbac(Object.assign(AdminRbac.defaultDeps(),
    { audit: auditPort,
      mode: rec.object('mode', req('common/mode')) }));
  const actions = new AdminActions(Object.assign(AdminActions.defaultDeps(),
    { auditLog: auditPort, applications: appsPort, roles: roles,
      rbac: rbac }));

  // ---- the role register (common/roles.js, rule 3u) -------------------
  const role = function (op, input, run) {
    rec.step(steps, 'roles', op, input, run);
  };
  ['', 'EVERYBODY', 'bad/name', 'ok name', 'x'.repeat(65), ' padded ']
    .forEach(function (name) {
      role('checkName', { name: name }, function () {
        return { problem: roles.checkName(name) };
      });
    });
  const write = function (name, record) {
    role('write', { name: name, record: record }, function () {
      return roles.write(name, record);
    });
  };
  write('staff', { description: 'The staff', users: ['dora'],
                   groups: ['g-staff'], displayName: ' Staff ' });
  write('bad/name', {});
  write('reader@app-res', { application: 'app-res' });
  write('reader', { application: 'app-res' });
  write('EVERYBODY@app-res', { application: 'app-res' });
  write('ADMIN_READ', { users: ['dora'] });
  write('robots', { memberTypes: 'robot user' });
  write('ADMIN_READ', { memberTypes: ['user'] });
  write('apps-only', { memberTypes: ['application'], users: ['dora'] });
  write('ADMIN_WRITE', { conferredBy: ['app-cli'] });
  write('apps-conf', { memberTypes: ['application'],
                       conferredBy: ['app-cli'] });
  write('nul-desc', { description: 'a\u0000b' });
  write('code-desc', { description: 'see STS-ADMIN-0001' });
  write('apps', { memberTypes: 'application, USER', applications: ['app-cli'],
                  permissions: ['https://api.example/write'],
                  conferredBy: ['app-cli', 'app-cli', ' '] });
  role('read', { name: 'staff' }, function () {
    return roles.read('staff');
  });
  role('read', { name: 'nosuch' }, function () {
    return roles.read('nosuch');
  });
  role('all', {}, function () {
    return roles.all();
  });
  role('catalogue', {}, function () {
    return roles.catalogue();
  });
  const owner = function (op, name, who) {
    role(op, { name: name, owner: who }, function () {
      return op === 'addOwner' ? roles.addOwner(name, who)
        : roles.removeOwner(name, who);
    });
  };
  owner('addOwner', 'nosuch', 'dora');
  owner('addOwner', 'staff', '');
  owner('addOwner', 'staff', 'nobody-at-all');
  owner('addOwner', 'staff', 'dora');
  owner('addOwner', 'staff', 'dora');
  owner('addOwner', 'staff', 'g-staff');
  owner('removeOwner', 'staff', 'emil');
  owner('removeOwner', 'nosuch', 'emil');
  role('setOwnerProtected', { name: 'staff', flag: true }, function () {
    return roles.setOwnerProtected('staff', true);
  });
  role('setOwnerProtected', { name: 'staff', flag: true }, function () {
    return roles.setOwnerProtected('staff', true);
  });
  role('setOwnerProtected', { name: 'nosuch', flag: true }, function () {
    return roles.setOwnerProtected('nosuch', true);
  });
  role('seedNativeRoles', {}, function () {
    return { made: roles.seedNativeRoles() };
  });
  ['admin:read', 'https://api.example/write', 'nothing'].forEach(function (p) {
    role('rolesAuthorizing', { permission: p }, function () {
      return roles.rolesAuthorizing(p);
    });
  });
  ['sts-admin-console', 'app-cli', ''].forEach(function (c) {
    role('conferredBy', { clientId: c }, function () {
      return roles.conferredBy(c);
    });
  });
  const contexts = [
    { kind: 'user', name: 'dora', authenticated: true },
    { kind: 'user', name: 'dora', authenticated: false },
    { kind: 'user', name: 'emil', authenticated: true,
      groups: ['g-staff', 'remote-peps'] },
    { kind: 'application', name: 'app-cli', authenticated: true },
    { kind: 'application', name: 'APP-CLI' },
    { kind: 'user', name: 'dora', authenticated: true, ids: true },
    { kind: 'user', name: 'dora', authenticated: true,
      application: 'app-res' },
    { kind: 'user', name: 'x', crossRealm: true, sids: ['g-staff'] },
    { kind: 'user', name: 'dora', authenticated: true, owns: true },
    {}
  ];
  contexts.forEach(function (who) {
    role('rolesOf', { who: who }, function () {
      return roles.rolesOf(who);
    });
    role('claimFor', { who: who }, function () {
      return roles.claimFor(who);
    });
  });
  [{ roles: ['a', ' b '] }, { roles: 'a, b  c' }, { roles: 7 }, {}, null,
   { roles: null }].forEach(function (claims) {
    role('rolesInClaims', { claims: claims }, function () {
      return roles.rolesInClaims(claims);
    });
  });

  // ---- the role actions (admin-core/admin_actions.ts rolesAction) -----
  const act = function (body) {
    rec.step(steps, 'roleActions', 'rolesAction', { body: body }, function () {
      return actions.rolesAction(body, { actor: 'vectors' });
    });
  };
  act({ action: 'create-role', role: 'a@b' });
  act({ action: 'create-role', role: 'r', application: 'nosuch-app' });
  act({ action: 'create-role', role: 'staff' });
  act({ action: 'create-role', role: 'bad/name' });
  act({ action: 'create-role', role: 'editors', description: 'Edit',
        displayName: 'Editors', memberTypes: 'user' });
  act({ action: 'create-role', role: 'viewer', application: 'app-res' });
  act({ action: 'describe-role', role: 'nosuch' });
  act({ action: 'describe-role', role: 'editors', description: 'New',
        memberTypes: [] });
  act({ action: 'add-member', role: 'editors', kind: 'robot',
        member: 'x' });
  act({ action: 'add-member', role: 'editors', kind: 'user' });
  act({ action: 'add-member', role: 'EVERYBODY', kind: 'user',
        member: 'dora' });
  act({ action: 'add-member', role: 'nosuch', kind: 'user',
        member: 'dora' });
  act({ action: 'add-member', role: 'editors', kind: 'user',
        member: 'dora' });
  act({ action: 'add-member', role: 'editors', kind: 'user',
        member: 'DORA' });
  act({ action: 'add-member', role: 'editors', kind: 'application',
        member: 'app-cli' });
  act({ action: 'remove-member', role: 'editors', kind: 'group',
        member: 'g-staff' });
  act({ action: 'remove-member', role: 'editors', kind: 'user',
        member: 'Dora' });
  act({ action: 'add-permission', role: 'nosuch' });
  act({ action: 'add-permission', role: 'EVERYBODY' });
  act({ action: 'add-permission', role: 'ADMIN_READ',
        permission: 'x' });
  act({ action: 'add-permission', role: 'editors' });
  act({ action: 'add-permission', role: 'editors',
        permission: 'admin:write' });
  act({ action: 'add-permission', role: 'editors',
        permission: 'https://nowhere.example/x' });
  act({ action: 'add-permission', role: 'editors',
        permission: 'https://api.example/write' });
  act({ action: 'add-permission', role: 'editors',
        permission: 'https://api.example/write' });
  act({ action: 'add-permission', role: 'editors',
        permission: 'https://api.example/read' });
  act({ action: 'remove-permission', role: 'editors',
        permission: 'https://api.example/nope' });
  act({ action: 'remove-permission', role: 'editors',
        permission: 'https://api.example/read' });
  act({ action: 'add-conferring-client', role: 'nosuch', client: 'app-cli' });
  act({ action: 'add-conferring-client', role: 'editors' });
  act({ action: 'add-conferring-client', role: 'editors',
        client: 'nosuch-app' });
  act({ action: 'add-conferring-client', role: 'editors', client: 'app-cli' });
  act({ action: 'add-conferring-client', role: 'editors', client: 'app-cli' });
  act({ action: 'remove-conferring-client', role: 'editors',
        client: 'app-res' });
  act({ action: 'remove-conferring-client', role: 'editors',
        client: 'app-cli' });
  act({ action: 'add-owner', role: 'editors', owner: 'emil' });
  act({ action: 'add-owner', role: 'editors', owner: 'emil' });
  act({ action: 'add-owner', role: 'editors', owner: '' });
  act({ action: 'remove-owner', role: 'editors', owner: 'nobody' });
  act({ action: 'remove-owner', role: 'editors', owner: 'emil' });
  act({ action: 'delete-role', role: 'EVERYBODY' });
  act({ action: 'delete-role', role: 'SSF_READ' });
  act({ action: 'delete-role', role: 'nosuch' });
  act({ action: 'delete-role', role: 'editors' });
  act({ action: 'bogus' });

  // ---- the console roster (admin-ui/admin_rbac.ts, rbac/grant) --------
  const grant = function (body) {
    rec.step(steps, 'rbac', 'rbacAction', { body: body }, function () {
      return actions.rbacAction(body, { actor: 'vectors', via: 'api' });
    });
  };
  grant({ action: 'grant', username: 'dora', role: 'nosuch' });
  grant({ action: 'grant', username: '', role: 'read' });
  grant({ action: 'grant', username: 'a,b', role: 'read' });
  grant({ action: 'grant', username: 'nobody-here', role: 'read' });
  grant({ action: 'grant', username: 'dora', role: 'READ' });
  grant({ action: 'grant', username: 'dora', role: 'read' });
  grant({ action: 'grant', username: 'emil', role: 'security' });
  grant({ action: 'revoke', username: '', role: 'read' });
  grant({ action: 'revoke', username: 'dora', role: 'nosuch' });
  grant({ action: 'revoke', username: 'emil', role: 'read' });
  grant({ action: 'revoke', username: 'dora', role: 'read' });
  grant({ action: 'revoke', username: 'emil', role: 'security' });
  grant({ action: 'promote' });

  // ---- a disabled account (common/account_state.ts, rule 3at) ---------
  const credentials = req('common/credentials');
  const stats = req('common/admin_stats');
  const realms = req('common/realms');
  const credPort = rec.object('credentials', credentials);
  const statsPort = rec.object('stats', stats);
  const revoking = req('common/revoking_writes');
  revoking.note = rec.fn('revokingWrites', 'note', revoking.note.bind(revoking));
  const mailUses = req('common/mail_uses');
  mailUses.accountDisabled = rec.fn('mail', 'accountDisabled',
    function () {
      return undefined;
    });
  const logoutPort = rec.object('logout', {
    terminate: function (key) {
      return { terminated: key === 'dora' ? ['s1', 's2'] : [], skipped: [],
               notifications: [], backchannel: key === 'dora' ? ['b1'] : [],
               message: 'ended what ' + key + ' held' };
    },
    heldIds: function () {
      return [];
    }
  });
  const AccountState = req('common/account_state').AccountState;
  const accountState = new AccountState({
    log: helpers.log, credentials: credPort, audit: auditPort,
    stats: statsPort, errorCodes: errorCodes, realms: realms,
    findLogout: function () {
      return logoutPort;
    },
    later: function () {
      return undefined;
    } });
  const account = function (op, input, run) {
    rec.step(steps, 'accountState', op, input, run);
  };
  [['', true], ['anonymous', true], ['dora', true], ['dora', true],
   ['dora', false], ['dora', false], ['ghost-person', true]]
    .forEach(function (row) {
      account('setDisabled', { who: row[0], disabled: row[1],
                               opts: { actor: 'vectors', via: 'api',
                                       reason: 'testing' } }, function () {
        return accountState.setDisabled(row[0], row[1],
          { actor: 'vectors', via: 'api', reason: 'testing' });
      });
    });
  account('setDisabled', { who: 'emil', disabled: true,
                           opts: { door: 'the password policy',
                                   riscReason: 'hijacking' } }, function () {
    return accountState.setDisabled('emil', true,
      { door: 'the password policy', riscReason: 'hijacking' });
  });
  ['', 'anonymous', 'dora', 'emil'].forEach(function (who) {
    account('isDisabled', { who: who }, function () {
      return { disabled: accountState.isDisabled(who) };
    });
  });

  // ---- the users and groups acts (admin_actions.ts usersAction, ------
  // groupsAction): the person created, the account switched, the group
  // written — the directory's half is the writer port.
  const mode = req('common/mode');
  mode.verifiesCredentials = rec.fn('mode', 'verifiesCredentials',
                                    mode.verifiesCredentials.bind(mode));
  const peopleActions = new AdminActions(Object.assign(
    AdminActions.defaultDeps(),
    { auditLog: auditPort, applications: appsPort, roles: roles, rbac: rbac,
      credentials: credPort, accountState: accountState,
      accountSignals: rec.object('accountSignals',
                                 req('ssf/account_signals')),
      serviceAccounts: rec.object('serviceAccounts',
                                  req('common/service_accounts')),
      serviceAccountPolicy: rec.object('serviceAccountPolicy',
                                       req('common/service_account_policy'))
    }));
  peopleActions.setDirectoryWriter(rec.fn('directory', 'createUser',
                                          ldap.createUser));
  peopleActions.setGroupWriter(rec.object('groups', {
    createGroup: ldap.createGroup, addGroupMember: ldap.addGroupMember,
    addGroupOwner: ldap.addGroupOwner,
    removeGroupOwner: ldap.removeGroupOwner,
    setGroupMail: ldap.setGroupMail, setGroupPolicy: ldap.setGroupPolicy }));
  peopleActions.mailedLink = rec.fn('actions', 'mailedLink',
    function () {
      return null;
    });
  const users = function (body) {
    rec.step(steps, 'users', 'usersAction', { body: body }, function () {
      return peopleActions.usersAction(body, { actor: 'vectors', via: 'api' });
    });
  };
  users({ action: 'create', username: 'frank', credential: 'none' });
  users({ action: 'create', username: 'gina', credential: 'password',
          password: 'Pw-1234567890!', passwordConfirm: 'other' });
  users({ action: 'create', username: 'hank', credential: 'password' });
  users({ action: 'create', username: 'ivan', credential: 'password',
          password: 'Correct-Horse-9-Battery!',
          'field.mail': 'ivan@example.com', 'field.cn': ' Ivan ',
          'field.telephoneNumber.0': '1', 'field.telephoneNumber.1': '2' });
  users({ action: 'create', username: 'jane', credential: 'generate',
          attributes: { sn: 'Jones' }, invent: 'no' });
  users({ action: 'create', username: 'kate', credential: 'bogus' });
  users({ action: 'create', username: 'lena', credential: 'activation' });
  users({ action: 'create', username: 'dora', credential: 'none' });
  users({ action: 'create', username: '', credential: 'none' });
  users({ action: 'create', username: 'a,b', credential: 'none' });
  users({ action: 'create', username: 'svc-one', credential: 'none',
          serviceAccount: 'true', owners: ['dora'] });
  users({ action: 'disable' });
  users({ action: 'disable', user: 'frank', riscReason: 'tired' });
  users({ action: 'disable', user: 'frank', riscReason: 'bulk-account' });
  users({ action: 'enable', username: 'frank' });
  users({ action: 'enable', username: '' });
  users({ action: 'fly' });
  const groups = function (body) {
    rec.step(steps, 'groups', 'groupsAction', { body: body }, function () {
      return peopleActions.groupsAction(body, { actor: 'vectors' });
    });
  };
  groups({ action: 'create', group: 'g-new', members: 'dora, emil\nfrank' });
  groups({ action: 'create', displayName: 'g-empty' });
  groups({ action: 'create', group: '' });
  groups({ action: 'create', group: 'g-new' });
  groups({ action: 'add-member', group: 'g-new', member: 'hank' });
  groups({ action: 'add-member', group: 'g-new', user: 'hank' });
  groups({ action: 'add-member', group: 'nosuch-group', member: 'hank' });
  groups({ action: 'set-mail', group: 'g-new', mail: 'team@example.com' });
  groups({ action: 'set-policy', group: 'g-new', attribute: 'x',
           policy: 'y' });
  groups({ action: 'add-owner', group: 'g-new', owner: 'dora' });
  groups({ action: 'remove-owner', group: 'g-new', owner: 'emil' });
  groups({ action: 'remove-member', group: 'g-new', member: 'hank' });

  // ---- the groups claim (common/group_claims.ts, rule 3d-ii) ----------
  const GroupClaims = req('common/group_claims').GroupClaims;
  const groupClaims = new GroupClaims({ log: helpers.log, config: config,
    applications: appsPort, stats: statsPort, errorCodes: errorCodes });
  groupClaims.setDirectory(rec.object('groups.directory',
                                      { groupsOfUser: ldap.groupsOfUser }));
  const claim = function (op, input, run) {
    rec.step(steps, 'groupClaims', op, input, run);
  };
  const claimSteps = function () {
    [['dora', ''], ['nobody-here', ''], ['dora', 'app-cli'], ['', '']]
      .forEach(function (row) {
        claim('groupsOf', { username: row[0], app: row[1] }, function () {
          return groupClaims.groupsOf(row[0], row[1]);
        });
      });
    claim('jwtClaimsFor', { set: 'id_token', context: { username: 'dora' } },
      function () {
        return groupClaims.jwtClaimsFor('id_token', { username: 'dora' });
      });
    ['saml2', 'saml11'].forEach(function (set) {
      claim('samlAttributesFor', { set: set,
                                   context: { subject: 'dora',
                                              client_id: 'app-cli' } },
        function () {
          return groupClaims.samlAttributesFor(set,
            { subject: 'dora', client_id: 'app-cli' });
        });
    });
    claim('state', {}, function () {
      return groupClaims.state();
    });
  };
  claimSteps();
  config.setOverride('groups.claimValue', 'dn');
  claimSteps();
  config.setOverride('groups.claimName', 'exp');
  claimSteps();
  config.clearOverride('groups.claimName');
  config.clearOverride('groups.claimValue');
  config.setOverride('groups.claim', false);
  claimSteps();
  config.clearOverride('groups.claim');

  // ---- ownership (common/ownership.ts, rule 3cn) -----------------------
  const Ownership = req('common/ownership').Ownership;
  const ownership = new Ownership({ log: helpers.log, errorCodes: errorCodes,
    config: function () {
      return config;
    },
    ldap: function () {
      return rec.object('ldap', ldap, ['groupsOfUser', 'groupsOwnedBy',
        'groupOwnership', 'setGroupOwnerProtected']);
    },
    roles: function () {
      return roles;
    },
    applications: function () {
      return appsPort;
    },
    serviceAccounts: function () {
      return rec.object('serviceAccounts', req('common/service_accounts'));
    },
    scopePolicy: function () {
      return rec.object('scopePolicy', req('common/scope_policy'));
    } });
  const own = function (op, input, run) {
    rec.step(steps, 'ownership', op, input, run);
  };
  ['dora', 'emil', 'nobody-here', ''].forEach(function (who) {
    own('identityOf', { username: who }, function () {
      return ownership.identityOf(who);
    });
    own('ownsAnything', { username: who }, function () {
      return { owns: ownership.ownsAnything(who) };
    });
  });
  [['role', 'staff'], ['role', 'ADMIN_READ'], ['role', 'EVERYBODY'],
   ['role', 'nosuch'], ['group', 'g-staff'], ['group', 'g-new'],
   ['group', 'admin-read'], ['application', 'app-res'],
   ['application', 'sts-api-client'], ['service-account', 'svc-one'],
   ['service-account', 'dora'], ['robot', 'x'], ['role', '']]
    .forEach(function (row) {
      own('objectOf', { kind: row[0], name: row[1] }, function () {
        return ownership.objectOf(row[0], row[1]);
      });
      own('owns', { username: 'dora', kind: row[0], name: row[1] },
        function () {
          return { owns: ownership.owns('dora', row[0], row[1]) };
        });
    });
  [['robot', 'x', true], ['role', '', true], ['role', 'staff', false],
   ['role', 'staff', 'true'], ['role', 'nosuch', true],
   ['group', 'g-new', true], ['application', 'app-res', true],
   ['application', 'app-res', false]].forEach(function (row) {
    own('setProtected', { kind: row[0], name: row[1], flag: row[2] },
      function () {
        return ownership.setProtected(row[0], row[1], row[2],
                                      { actor: 'vectors' });
      });
  });

  // ---- the permission register (common/app_permissions.ts, rule 3s) ---
  const AppPermissions = req('common/app_permissions').AppPermissions;
  const appPermissions = new AppPermissions({ log: helpers.log,
    applications: appsPort, errorCodes: errorCodes });
  const perm = function (op, input, run) {
    rec.step(steps, 'appPermissions', op, input, run);
  };
  perm('register', {}, function () {
    return appPermissions.register();
  });
  ['app-res', 'app-cli', 'nosuch'].forEach(function (id) {
    perm('forApplication', { identifier: id }, function () {
      return appPermissions.forApplication(id);
    });
  });
  const permAct = function (op, args) {
    perm(op, { args: args }, function () {
      return appPermissions[op].apply(appPermissions, args);
    });
  };
  permAct('definePermission', ['app-res', 'admin', 'Administer it']);
  permAct('definePermission', ['app-res', 'bad name', '']);
  permAct('definePermission', ['nosuch', 'x', '']);
  permAct('removePermission', ['nosuch', 'x', 'vectors']);
  permAct('removePermission', ['app-res', 'zzz', 'vectors']);
  permAct('grant', ['app-cli', 'https://api.example/admin', 'vectors']);
  permAct('grant', ['app-cli', 'https://api.example/write', 'vectors']);
  permAct('grant', ['app-cli', 'https://nowhere.example/x', 'vectors']);
  permAct('removePermission', ['app-res', 'admin', 'vectors']);
  permAct('revoke', ['app-cli', 'https://api.example/admin', 'vectors']);
  permAct('revoke', ['app-cli', 'https://never.example/x', 'vectors']);
  perm('register', {}, function () {
    return appPermissions.register();
  });
  permAct('setBaseUri', ['app-cli', 'urn:cli:', 'vectors']);
  permAct('setBaseUri', ['app-cli', 'https://cli.example', 'vectors']);
  permAct('setBaseUri', ['app-cli', '', 'vectors']);
  permAct('setBaseUri', ['nosuch', 'https://x.example', 'vectors']);

  // ---- the /admin-api/permissions acts (permissionsAction) -----------
  const permActions = new AdminActions(Object.assign(
    AdminActions.defaultDeps(), { appPermissions: appPermissions }));
  [{ action: 'define-permission', name: 'x' },
   { action: 'grant-permission', permission: 'y' },
   { action: 'define-permission', resource: 'app-res', name: 'audit',
     description: 'Read the audit' },
   { action: 'remove-permission', resource: 'app-res', name: 'nope' },
   { action: 'grant-permission', client: 'app-cli',
     permission: 'https://api.example/audit' },
   { action: 'revoke-permission', client: 'app-cli',
     permission: 'https://api.example/audit' },
   { action: 'set-permission-base', resource: 'nosuch', baseUri: 'x' },
   { action: 'remove-permission', resource: 'app-res', name: 'audit' },
   { action: 'shout' }].forEach(function (body) {
    rec.step(steps, 'permissionActions', 'permissionsAction', { body: body },
      function () {
        return permActions.permissionsAction(body, { actor: 'vectors' });
      });
  });

  // ---- a role authorizing a permission (role_permissions.ts, 3bq) -----
  const gate = req('common/issuance_gate');
  gate.checkScopes = rec.fn('gate', 'checkScopes', gate.checkScopes);
  helpers.subjectIsGone = rec.fn('helpers', 'subjectIsGone',
                                 helpers.subjectIsGone);
  helpers.nameForSubject = rec.fn('helpers', 'nameForSubject',
                                  helpers.nameForSubject);
  mode.refusesTokenForGoneSubject = rec.fn('mode',
    'refusesTokenForGoneSubject', mode.refusesTokenForGoneSubject.bind(mode));
  const RolePermissions = req('common/role_permissions').RolePermissions;
  const ownershipModule = req('common/ownership');
  const rolePermissions = new RolePermissions({ log: helpers.log,
    realms: realms, roles: roles, applications: appsPort, audit: auditPort,
    adminRbac: rec.object('rbac', adminRbacModule,
                          ['rolesOf', 'noteConsoleSignIn']),
    ownsAnything: rec.fn('ownership', 'ownsAnything',
                         ownershipModule.ownsAnything) });
  const rp = function (op, input, run) {
    rec.step(steps, 'rolePermissions', op, input, run);
  };
  ['admin:read', 'owner:write', 'https://api.example/write',
   'https://api.example/read', 'openid', ''].forEach(function (value) {
    rp('isGated', { value: value }, function () {
      return { gated: rolePermissions.isGated(value),
               application: rolePermissions.isApplicationPermission(value) };
    });
  });
  const subjects = [{ kind: 'user', name: 'dora' },
    { kind: 'user', name: 'dora', authenticated: false },
    { kind: 'user', name: 'emil' },
    { kind: 'application', name: 'app-cli' },
    { kind: 'application', name: 'sts-api-client' }, {}];
  subjects.forEach(function (who) {
    rp('heldRoles', { subject: who }, function () {
      return rolePermissions.heldRoles(who);
    });
    rp('asksFor', { scope: 'openid https://api.example/read', subject: who },
      function () {
        return { asks: rolePermissions.asksFor(
          'openid https://api.example/read', who) };
      });
    rp('conferredOn', { subject: who, clientId: 'sts-admin-console' },
      function () {
        return rolePermissions.conferredOn(who, 'sts-admin-console');
      });
  });
  [['openid profile', { kind: 'user', name: 'dora' }, {}],
   ['openid admin:read https://api.example/write',
    { kind: 'user', name: 'dora' }, { clientId: 'app-cli', record: false }],
   ['admin:read admin:write', { kind: 'user', name: 'emil' },
    { clientId: 'sts-admin-console', grant: 'authorization_code' }],
   ['https://api.example/read ssf.read', { kind: 'application',
     name: 'app-cli' }, { clientId: 'app-cli', grant: 'client_credentials' }],
   ['admin:read', { kind: 'user', name: 'x', authenticated: false },
    { clientId: 'app-cli' }]].forEach(function (row) {
    rp('narrowScope', { scope: row[0], subject: row[1], context: row[2] },
      function () {
        return rolePermissions.narrowScope(row[0], row[1], row[2]);
      });
  });
  [[{ client_id: 'app-cli', sub: 'app-cli' }, ['https://api.example/write']],
   [{ client_id: 'sts-admin-console', sub: 'dora' },
    ['admin:read', 'admin:write', 'admin:console']],
   [{ client_id: 'app-cli', sub: 'urn:uuid:nobody' }, ['admin:read']]]
    .forEach(function (row) {
      rp('effectiveRoles', { claims: row[0], carried: row[1] }, function () {
        return rolePermissions.effectiveRoles(row[0], row[1], '');
      });
    });

  config.value = realValue;
  return { steps: steps };
}

module.exports = { build: build, recorder: recorder, clone: clone };
